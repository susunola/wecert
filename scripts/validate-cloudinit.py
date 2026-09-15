#!/usr/bin/env python3
"""在 apply 之前校验 cloud-init user_data。

为什么需要这个脚本：user_data 里的脚本只有机器真正启动后才会执行，
写错语法要等 CVM 建完、后端起不来才暴露 —— 一次白等好几分钟，
而且现象是"CLB 返回 502"，很容易误判成网络或安全组问题。

实测就踩过：Python 里一个字符串引号不匹配，CVM 建出来了、
cloud-init 也"成功"了（runcmd 里的 systemctl 静默失败），
但后端一直不监听 80。

默认从 .tf 源码解析（apply 之前就能查）；
加 --from-state 改成从 terraform state 里取（更权威，但要先 apply 过）。

用法：
    python3 scripts/validate-cloudinit.py
    python3 scripts/validate-cloudinit.py testenv/cvm.tf
    python3 scripts/validate-cloudinit.py --from-state testenv
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap


def extract_from_tf(path):
    """从 .tf 源码里提取 write_files 的 (path, content)。"""
    lines = open(path, encoding="utf-8").read().split("\n")
    found = []
    cur_path = None

    i = 0
    while i < len(lines):
        line = lines[i]

        m = re.match(r"^\s*-\s*path:\s*(\S+)\s*$", line)
        if m:
            cur_path = m.group(1)
            i += 1
            continue

        m = re.match(r"^(\s*)content:\s*\|", line)
        if m and cur_path:
            indent = len(m.group(1))
            body = []
            i += 1
            while i < len(lines):
                nxt = lines[i]
                # 缩进回到 content 同级或更浅，说明这个 block 结束了
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                body.append(nxt)
                i += 1
            found.append((cur_path, textwrap.dedent("\n".join(body))))
            cur_path = None
            continue

        i += 1

    return found


def _try_b64(raw):
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8")
    except Exception:
        return None


def extract_from_state(tf_dir):
    out = subprocess.run(
        ["terraform", "show", "-json"],
        cwd=tf_dir, capture_output=True, text=True, check=True,
    ).stdout
    state = json.loads(out)

    for res in state.get("values", {}).get("root_module", {}).get("resources", []):
        if res["type"] != "tencentcloud_instance":
            continue
        values = res["values"]
        raw = values.get("user_data_raw") or values.get("user_data") or ""
        if not raw:
            continue
        # provider 对 user_data 存的是 base64；user_data_raw 可能是明文
        for candidate in (raw, _try_b64(raw)):
            if candidate and candidate.lstrip().startswith("#cloud-config"):
                return res["name"], candidate
    return None, None


def check_python(name, content, failures):
    try:
        compile(content, name, "exec")
        print(f"    OK   Python 语法合法   {name}")
    except SyntaxError as e:
        print(f"    FAIL Python 语法错误   {name}:{e.lineno}: {e.msg}")
        print(f"         {(e.text or '').rstrip()}")
        failures.append(f"{name} 第 {e.lineno} 行: {e.msg}")


def check_shell(name, content, failures):
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        r = subprocess.run(["bash", "-n", tmp], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"    OK   shell 语法合法    {name}")
        else:
            print(f"    FAIL shell 语法错误    {name}\n         {r.stderr.strip()}")
            failures.append(f"{name}: {r.stderr.strip()}")
    finally:
        os.unlink(tmp)


def classify_and_check(name, content, failures):
    first = content.split("\n", 1)[0]
    if first.startswith("#!") and "python" in first:
        check_python(name, content, failures)
    elif first.startswith("#!"):
        check_shell(name, content, failures)
    elif name.endswith(".py"):
        check_python(name, content, failures)
    else:
        print(f"    --   跳过（非脚本）     {name}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    from_state = "--from-state" in sys.argv
    failures = []

    if from_state:
        tf_dir = args[0] if args else "testenv"
        if not os.path.isdir(tf_dir):
            print(f"找不到目录 {tf_dir}", file=sys.stderr)
            return 2
        try:
            name, user_data = extract_from_state(tf_dir)
        except subprocess.CalledProcessError as e:
            print(f"terraform show 失败: {e.stderr}", file=sys.stderr)
            return 2
        if not user_data:
            print("state 里没有带 user_data 的实例，跳过。")
            return 0

        print(f"从 state 校验实例 {name} 的 user_data（{len(user_data)} 字节）")
        try:
            import yaml
        except ImportError:
            print("  需要 pyyaml 才能解析 cloud-init（pip install pyyaml）")
            return 0
        try:
            doc = yaml.safe_load(user_data)
        except Exception as e:
            print(f"  FAIL YAML 解析失败: {e}")
            return 1
        if not isinstance(doc, dict):
            print("  FAIL 不是合法的 cloud-init 映射")
            return 1
        print("  OK   YAML 合法")

        files = [(f.get("path", "?"), f.get("content") or "")
                 for f in (doc.get("write_files") or [])]
    else:
        tf_file = args[0] if args else os.path.join("testenv", "cvm.tf")
        if not os.path.isfile(tf_file):
            print(f"找不到文件 {tf_file}", file=sys.stderr)
            return 2
        print(f"从源码校验 {tf_file}")
        files = extract_from_tf(tf_file)

    if not files:
        print("  没提取到 write_files 内容，检查 .tf 写法是否变了。")
        return 1

    print(f"  write_files: {len(files)} 个")
    for name, content in files:
        classify_and_check(name, content, failures)

    if failures:
        print(f"\nFAIL 校验失败，共 {len(failures)} 个问题：")
        for x in failures:
            print(f"   - {x}")
        return 1

    print("\nOK cloud-init user_data 语法校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
