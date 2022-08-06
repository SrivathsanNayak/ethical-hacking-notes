# Committed - Easy

```shell
cd /home/ubuntu/committed/committed

git status

git log

ls

git checkout -f dbint

git reset --hard HEAD~1

cat Note

cat main.py

cat Readme.md
```

```markdown
We are given a zip file containing the committed folder.

On unzipping it, we can check if it contains any clues.

Using git status, we find that all code has been committed and pushed.

git log shows that there are previous versions of the code as well.

We can view the files but they do not contain anything, so we can check previous commits.

Using git reset, we can go commit-by-commit to check for the flag.

Also, git branch shows us another branch, so we can switch to that and check for flag.

dbint includes a Note as well, we can check that.

By moving one commit at a time, using git reset --hard, we can check the edits done to the files.

In the dbint branch, we will eventually get the flag in main.py file, in an older commit.
```

```markdown
1. Discover the flag in the repository. - flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}
```
