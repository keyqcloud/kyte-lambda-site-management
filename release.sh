#!/bin/bash

print_error() {
    echo "\033[1;31m$1\033[0m"  # Added -e to enable interpretation of backslash escapes
}

check_success() {
    if [ $? -eq 0 ]; then
        echo "$1"
    else
        print_error "$2"
        exit 1
    fi
}

create_zip() {
    cd "$1" || exit
    zip -r "..//releases/latest/$1.zip" .
    check_success "ZIP file created successfully." "Failed to create ZIP file."

    cp "../releases/latest/$1.zip" "../releases/archive/$1-$2.zip"

    cd "../"
    
    echo "Archive updated with version $2."
}

if [ "$#" -eq 1 ]; then
    changelog_version=$(awk '/## /{print $2;exit}' CHANGELOG.md)
    if [ "$changelog_version" != "$1" ]; then
        print_error "Version in CHANGELOG.md does not match the release version."
        exit 1
    fi

    create_zip "kyte-site-management" "$1"
    
    echo "Creating tag for release version $1"

    git add .
    git commit -m "release $1"
    git push
    check_success "Committed and pushed $1 to git" "Git push failed."

    git tag "v$1"
    check_success "Git tag created successfully for v$1." "Git tag creation failed."

    git push origin --tags
    check_success "Git push successful. New release v$1 is available" "Git push failed."
else
    print_error "Usage: $0 [version]"
fi
