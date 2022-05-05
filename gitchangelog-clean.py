import re

def remove_names():
    with open("CHANGELOG.rst", "r") as changelog_file:
        changelog = changelog_file.read()
    changelog = re.sub('\s\[.*(\n\s\s.*)*\]', '', changelog)
    with open("CHANGELOG.rst", "w") as changelog_file:
        changelog_file.write(changelog)


if __name__ == "__main__":
    remove_names()