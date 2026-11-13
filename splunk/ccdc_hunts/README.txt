CCDC Hunts 2.2 - a Splunk app is just a folder of text files.

WHAT'S INSIDE
  default/macros.conf          Where each log lives (windows_security, linux_auth, web_access, ...).
                               Change an index or source here once and every alert and panel follows.
                               expected_hosts = the hosts that should be sending logs. Edit it in
                               Settings > Advanced search > Search macros (UI edits survive upgrades).
  default/savedsearches.conf   32 alerts. Each runs every 5 minutes. Hits show under Activity > Triggered Alerts.
                               Each alert's description links to its section of the response playbook.
  default/data/ui/views/       8 dashboards: Overview, Remote Execution, Accounts & Logons,
                               Persistence & Tampering, Linux, Web Email & FTP, Network, Health & Splunk.
  default/data/ui/nav/         The menu bar (with a Playbook link).
  appserver/static/playbook.pdf
      Please use this --->     The response playbook. Splunk serves it at /en-US/static/app/ccdc_hunts/playbook.pdf,
                               so it works with no internet. Every alert panel links to its own section
                               (#page=N&nameddest=<section>). Every Splunk search printed in it (the blue
                               "Run in Splunk" tabs) is a link that opens Search with it filled in and run.
                               Those links only work when the PDF is opened from Splunk (the Playbook menu),
                               not from a downloaded copy. Ctrl+click one to open it in a new tab.
                               To update it, replace this file and open
                               http://<splunk>:8000/en-US/_bump so Splunk stops serving the cached copy.
  metadata/default.meta        Makes everything visible from every app.
  examples/                    Config to copy onto forwarders and the Splunk server. Splunk ignores this folder.

!!!!IMPORTANT!!!!
FIRST STEPS AFTER INSTALLING
  1. Settings > Advanced search > Search macros > expected_hosts: replace CHANGE_ME with every host that
     should send logs, comma separated, exactly as the Health & Splunk dashboard's "Last data per host
     and log" panel shows them. Until you do, Host stopped sending logs fires for "change_me".
  2. Open Health & Splunk and check every expected host says OK.
  3. Dashboards that stay empty usually mean that log isn't coming in yet. See examples/.


ADDING YOUR OWN
  New alert: copy a [stanza] in savedsearches.conf, rename it, change "search =".
  New dashboard: copy a file in views/, change <label>, add <view name="..."/> to nav/default.xml.
