#!/bin/bash

set -eu -o pipefail

TAG=$(perl -MFile::Slurp::Tiny=read_file -MDateTime <<'EOF'
use v5.16;
my $log = read_file(q{Changes.md});
$log =~ /^## (\d+\.\d+\.\d+) - (\d{4}-\d{2}-\d{2})\n/;
die "Release time of $2 is not today!" unless DateTime->now->ymd eq $2;
say $1;
EOF
)

if [ -n "$(git status --porcelain)" ]; then
    echo ". is not clean." >&2
    exit 1
fi

perl -i -pe "s/(?<=AC_INIT\(\[mod_maxminddb\], ?\[)(\d+\.\d+\.\d+)(?=\])/$TAG/" configure.ac;

if [ -z "$(git status --porcelain)" ]; then
    echo 'Failed to update configure.ac'
    exit 1
fi

git add configure.ac
git commit -m "Bumped version to $TAG"

./bootstrap
./configure
make dist

if [ ! -d .gh-pages ]; then
    echo "Checking out gh-pages in .gh-pages"
    git clone -b gh-pages git@github.com:maxmind/mod_maxminddb.git .gh-pages
    pushd .gh-pages
else
    echo "Updating .gh-pages"
    pushd .gh-pages
    git pull
fi

if [ -n "$(git status --porcelain)" ]; then
    echo ".gh-pages is not clean" >&2
    exit 1
fi

INDEX=index.md
cat <<EOF > $INDEX
---
layout: default
title: mod_maxminddb - an Apache module that allows you to query MaxMind DB files
version: $TAG
---
EOF

cat ../README.md >> $INDEX

if [ -n "$(git status --porcelain)" ]; then
    git commit -m "Updated for $TAG" -a

    read -p "Push to origin? (yN) " SHOULD_PUSH

    if [ "$SHOULD_PUSH" != "y" ]; then
        echo "Aborting"
        exit 1
    fi

    git push
fi

popd

git tag -a -m "Release for $TAG" $TAG
git push --follow-tags
