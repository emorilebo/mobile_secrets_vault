# Publishing Guide: PyPI Trusted Publishing

You are setting up **Trusted Publishing** (OIDC) on PyPI. This is excellent! It's more secure and easier to manage than API tokens because you don't need to copy/paste secrets into GitHub.

## 1. Update Your Code (I have done this for you)

I have updated your `.github/workflows/ci.yml` file to support Trusted Publishing. You need to push these changes to GitHub before the publishing will work.

```bash
git add .github/workflows/ci.yml
git commit -m "Configure Trusted Publishing for PyPI"
git push origin main
```

## 2. Fill Out the PyPI Form

Use these **exact values** for the form in your screenshot:

| Field | Value | Notes |
|-------|-------|-------|
| **PyPI Project Name** | `mobile-secrets-vault` | This must match the `name` in your `pyproject.toml` |
| **Owner** | `emorilebo` | Your GitHub username |
| **Repository name** | `mobile_secrets_vault` | The name of your repo |
| **Workflow name** | `ci.yml` | The filename of the workflow |
| **Environment name** | `pypi` | I added this to the workflow config |

## 3. Publish a Release

Once you have added the publisher on PyPI and pushed the updated code to GitHub:

1. Create a new release on GitHub (e.g., `v0.1.0`).
2. The GitHub Action will automatically run.
3. It will authenticate with PyPI using OIDC (no password needed!) and upload your package.

## Troubleshooting

- **"Pending Publisher"**: If this is the *first* time you are publishing this package, PyPI will create it as a "Pending Publisher". The package will be created automatically when your GitHub Action runs successfully for the first time.
- **Environment**: If the GitHub Action fails saying "Environment 'pypi' not found", you may need to create the Environment in GitHub Settings -> Environments, but usually GitHub creates it automatically or it just works for public repos.
