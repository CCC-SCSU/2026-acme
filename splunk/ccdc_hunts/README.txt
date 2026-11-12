CCDC Hunts - a Splunk app is just a folder of text files.

default/macros.conf          Where the logs live (index/source). Change the index here once.
default/savedsearches.conf   The detections. One [stanza] per detection, runs every 5 minutes.
                             Hits appear under Activity > Triggered Alerts.
default/data/ui/views/       The dashboard (Remote Execution Hunt).
default/data/ui/nav/         The app's menu bar.
default/app.conf             App name and version.
metadata/default.meta        Makes the searches and macros visible in every app.

To add a detection: copy a [stanza] in savedsearches.conf, give it a new name,
change the search line, and restart Splunk (or re-upload the app).
