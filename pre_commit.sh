#!/usr/bin/env bash
# 'set -e' stops the execution of a script if a command or pipeline has an error.
# This is the opposite of the default shell behaviour, which is to ignore errors in scripts.
set -e

clean_docs() {
  rm -rf docs  && mkdir docs
}

update_release_notes() {
  # Update release notes
  if ! [ -x "$(command -v gitverse)" ]; then
    pip install gitverse
  fi
  gitverse-release reverse -f release_notes.rst -t 'Release Notes'
}

gen_docs() {
  # Generate sphinx docs
  mkdir -p doc_gen/_static  # Create a _static directory if unavailable
  cp README.md doc_gen  # Copy readme file to doc_gen
  cd doc_gen && make clean html  # cd into doc_gen and create the runbook
  mv _build/html/* ../docs && mv README.md ../docs  # Move the runbook, readme and cleanup
  cp -p static.css ../docs/_static
}

run_pytest() {
  # Run pytest
  python -m pytest
}

gen_docs &
clean_docs &
update_release_notes &

wait

# The existence of this file tells GitHub Pages not to run the published files through Jekyll.
# This is important since Jekyll will discard any files that begin with _
touch docs/.nojekyll
