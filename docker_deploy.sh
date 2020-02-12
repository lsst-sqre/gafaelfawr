#!/bin/bash

image="lsstdm/jwt_authorizer"
commit=$(git rev-parse HEAD)
pull_request=$1
tag=$2

if [[ -z $branch ]]; then
    branch=$(git rev-parse --abbrev-ref HEAD)
fi

dirty_files=$(git diff-index HEAD --  | wc -l | awk '{print $1}')
untracked_files=$(git ls-files --exclude-standard --others | wc -l | awk '{print $1}')
postfix=""

if [[ $dirty_files -gt 0 ]]; then
    postfix+="-dirty_$dirty_files"
fi

# Untracked files shouldn't show up in Dockerfile
# Thanks to .dockerignore
#if [[ $untracked_files -gt 0 ]]; then
#    postfix+="-u$untracked_files"
#fi

commit_describe=$(echo $commit | cut -c1-7)$postfix
commit_tag=$image:$commit_describe

docker build -t $commit_tag --build-arg=COMMIT=$commit --build-arg=COMMIT_DESCRIBE=$commit_describe --build-arg=BRANCH=$branch .
echo "Building container for $branch"

if [[ $branch == "master" || $TRAVIS_BRANCH == "master" ]]; then
    docker_tag="$image:latest"
    docker tag $commit_tag $docker_tag
    docker push $docker_tag
fi

if [[ $pull_request -gt 0 ]]; then
    docker_tag="$image:pull_request_$pull_request"
    docker tag $commit_tag $docker_tag
    docker push $docker_tag
fi

if [[ -n $tag ]]; then
    docker_tag=$image:$tag
    docker tag $commit_tag $docker_tag
    docker push $docker_tag
fi
