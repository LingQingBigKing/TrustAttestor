# Git push guard

`pre-push` rejects commits that contain Android/Gradle build output, APK/DEX
artifacts, signing stores, or local environment files. The current checkout is
configured with `core.hooksPath=.githooks`.

The build root should be an external directory outside this repository. For a
fresh clone, enable the guard with:

```powershell
git config core.hooksPath .githooks
```
