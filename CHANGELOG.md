## Changelog
### 2/18/18
- Added:
  - `Last Request` indicator to give some sort of idea where the progress is.
- Todo:
  - `Progress Bar` - either a percentage or how many domains out of which. This is sort of a challenge with the concurrency.
### 1/17/18
- Removed:
  - `ulimit function` Raising the ulimit was a temporary fix to a "too many open files" socket error that would kill the program.
- Added:
  - `Windows compatibility` since we no longer need to raise the ulimit.
  - `Cleaned code` to be a little more efficient and formatted with gofmt.
### 12/10/17
- Removed:
  - `Banner` (I hate banners actually.)
- Added:
  - `Strict feature` keeps the option to make HTTP requests to every URL, this finds sites vulnerable that have A records attached instead of CNAMEs.
  - `Detection via DNS` [(Because this is **a lot faster/smarter** than making HTTP requests to every URL)](https://github.com/haccer/subjack/issues/1)
- Fixed:
  - `Pesky 408 errors` that were annoying me (Thanks DNS Detection.)
