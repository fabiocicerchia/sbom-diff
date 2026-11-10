@domain:documentation-site @area:site-theme @from:stylesheets/extra
Feature: Keeping the documentation site on one self-contained look
  Gives readers of the sbom-diff docs and splash page one consistent, privacy-respecting look in light and dark mode, without anything fetched from third parties.

  Background:
    Given the sbom-diff documentation site is published with its splash page and its rendered guides

  @id:docs.documentation-site.site-theme.002 @rule:docs.theme.no-external-assets @inferred @source:docs/stylesheets/extra.css#:root
  Scenario: The site theme loads no fonts or assets from outside sources
    Given the reader's browser blocks every request to third-party hosts
    When a reader opens any documentation page
    Then body text is set in the operating system's own sans-serif font
    And code is set in the operating system's own monospace font
    And the page appears fully styled with no font or stylesheet fetched from a CDN

  @id:docs.documentation-site.site-theme.004 @rule:docs.theme.no-placeholder-logo @inferred @source:docs/stylesheets/extra.css#.md-header__button.md-logo
  Scenario: The header shows no stand-in logo while the project has none
    Given the project has no logo configured for the site
    When a reader opens a documentation page
    Then the header and navigation drawer show the project title without any logo icon
