#!/bin/bash

auth_token=$(gh auth token)
gh_owner=project-purcellville
#gh_path=cgc-challenges
#gh_path=cgc-challenges/linux-build/challenges/AIS-Lite
gh_path=cgc-challenges/linux-build/challenges/Particle_Simulator
gh_file_repo=direct-file-store-0000
gh_snapshot_token=$(cat ~/.github-snapshots-workflow-access-token.txt)
gh_snapshot_repo=snapshots-0000

gh act \
   -W ./.github/workflows/corpus_test.yml \
   -s GITHUB_TOKEN=$auth_token \
   -s CORPUS_ACCESS_TOKEN=$auth_token \
   -s SNAPSHOT_ACCESS_TOKEN=$gh_snapshot_token \
   --var CORPUS_GITHUB_OWNER=$gh_owner \
   --var CORPUS_GITHUB_PATH=$gh_path \
   --var CORPUS_GITHUB_REPO=$gh_file_repo \
   --var SNAPSHOT_GITHUB_OWNER=$gh_owner \
   --var SNAPSHOT_GITHUB_REPO=$gh_snapshot_repo \
   -v
