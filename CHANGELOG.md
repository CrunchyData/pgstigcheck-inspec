# Changelog
All notable changes to crunchy-hugo-theme will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Develop]

### Added

### Changed

### Removed

### Fixed

## [2.2.0] - 2019-02-23

### Removed

- Removed references to a Highlight JavaScript file which was not in use.

### Fixed

- The chevron FontAwesome icons on the side navigation menu for the crunchy-containers and postgres-operator projects were originally "not found" on page load of specifically parent pages with children, and the icons would not show as expected. They now load as expected.

- A jQuery scroll fix was added; when clicking on an anchor, the header for that section no longer hides behind the top sticky navigation menu.
