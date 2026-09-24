# GitHub Support request: clear stale contributors from hidden PR refs

**Repo:** https://github.com/susunola/wecert  
**Asks:** (1) reset/rebuild the contributor graph, and if possible (2) remove or anonymise orphaned `refs/pull/*/head` commits that are no longer reachable from any branch.

---

## Subject

Request contributor graph reset and cleanup of orphaned `refs/pull/*/head` (susunola/wecert)

## Body

Hello,

I maintain **susunola/wecert**. I rewrote the full Git history so that **every commit is authored and committed by `susunola`**, then force-pushed `main`, all other branches, and all version tags.

### What is already clean

- `GET /repos/susunola/wecert/contributors` returns **only `susunola`**.
- Every commit on `main` and every other `refs/heads/*` has author/committer `susunola`.
- Commit messages no longer contain `Co-authored-by`, `Signed-off-by: dependabot`, or other third-party trailers.

I also removed `.github/dependabot.yml` so the Dependabot app will not open new PRs.

### What still shows on the repository home page

The **Contributors** sidebar still lists three accounts:

- `susunola`
- `dependabot[bot]`
- `claude` (Claude)

This appears to come from **orphaned `refs/pull/*/head` snapshots**, not from any branch. There are **93** pull refs, pointing at pre-rewrite commits whose authors include:

- `Claude <noreply@anthropic.com>`
- `dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>`
- `atomoswang <atomoswang@tencent.com>`

Those commits are **not** reachable from `main` or from any remaining branch. The PR source branches were deleted after merge; the PRs themselves are all **closed**. I cannot update those refs (`git push` to `refs/pull/N/head` is rejected: “deny updating a hidden ref”), and the REST API has no way to delete a pull request.

`https://github.com/susunola/wecert/graphs/contributors` also still shows `dependabot` with 2 contributions even though the official contributors API does not.

### Request

Please, if possible:

1. **Rebuild or reset the contributor graph** for `susunola/wecert` so it matches the current default-branch history (only `susunola`).
2. **Delete or rewrite the orphaned `refs/pull/*/head` refs** (or stop counting commits that are only reachable from those refs) so `dependabot[bot]`, `claude`, and `atomoswang` no longer appear as contributors.

I understand PR metadata (PR author field) may remain on historical pull request pages; I only need them **out of Contributors**.

Happy to verify identity as the repository owner.

Thank you,
susunola

---

## 如何提交

1. 打开 https://support.github.com/contact （或 GitHub 右上角 **?** → **Contact GitHub**）。
2. 账号用 **susunola**（仓库 owner）。
3. 粘贴上面 **Subject / Body**。
4. 若表单要 URL，填：`https://github.com/susunola/wecert`  
   若要选类型：**Account / Repository** → **Data is wrong / contributor graph**。

---

## 若 Support 不处理（方案 3 · 核弹）

新建同名干净仓库，只推现在的 `main` + tags，再改名接管 `wecert`。会丢掉 Issues / PR / Actions 历史。需要的话我来执行。
