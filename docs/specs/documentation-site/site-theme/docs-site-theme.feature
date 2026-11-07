@domain:documentation-site @area:site-theme @from:stylesheets/extra
Feature: Keeping the documentation site on one self-contained look
  Gives readers of the sbom-diff docs and splash page one consistent, privacy-respecting look in light and dark mode, without anything fetched from third parties.

  Background:
    Given the sbom-diff documentation site is published with its splash page and its rendered guides

  @id:docs.documentation-site.site-theme.001 @rule:docs.theme.single-shared-accent-palette @inferred @source:docs/stylesheets/extra.css#:root @questionable
  Scenario: The splash page and the guides share one accent palette
    Given the site's accent pair is orange #fb923c with red #ef4444
    When a reader opens the splash page and then a guide page
    Then the splash title, primary buttons and the guide hero heading show the same orange-to-red gradient
    And links and the header chrome on the light scheme are red #ef4444
    And both pages show the same two accent colours

  @id:docs.documentation-site.site-theme.002 @rule:docs.theme.no-external-assets @inferred @source:docs/stylesheets/extra.css#:root
  Scenario: The site theme loads no fonts or assets from outside sources
    Given the reader's browser blocks every request to third-party hosts
    When a reader opens any documentation page
    Then body text is set in the operating system's own sans-serif font
    And code is set in the operating system's own monospace font
    And the page appears fully styled with no font or stylesheet fetched from a CDN

  @id:docs.documentation-site.site-theme.003 @rule:docs.theme.dark-scheme-ground @inferred @source:docs/stylesheets/extra.css#[data-md-color-scheme="slate"]
  Scenario: The dark scheme uses a near-black ground with accent-coloured links
    Given the reader's system prefers a dark colour scheme
    When a reader opens a documentation page
    Then the page background, header and navigation tabs are near-black #0b0f1a
    And links are orange #fb923c

  @id:docs.documentation-site.site-theme.004 @rule:docs.theme.no-placeholder-logo @inferred @source:docs/stylesheets/extra.css#.md-header__button.md-logo
  Scenario: The header shows no stand-in logo while the project has none
    Given the project has no logo configured for the site
    When a reader opens a documentation page
    Then the header and navigation drawer show the project title without any logo icon
