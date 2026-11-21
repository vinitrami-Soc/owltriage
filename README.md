# OwlTriage rules pack

This branch is written by the `Rules pack` workflow. Do not edit it by hand.

`owltriage-rules.json` holds the detection rules from `main`, signed with the maintainers' key.
`owltriage update-rules` downloads it, checks the signature against the key built into owltriage,
and installs it only if it is newer than the rules you have and every rule passes its own tests.

On a machine without internet access, download the file elsewhere and run:

    owltriage update-rules --file owltriage-rules.json

Every commit on this branch is one published pack, so the history is the audit trail.
