.. :changelog:

Release History
===============


0.1.11
++++++
Including pwinput in code to workaround the issue with azure cli version >= 2.42.0 in windows installed using MSI.
Issue link: https://github.com/Azure/azure-cli/issues/24781

0.1.10
++++++
* Bug Fix: Wait for SystemAssigned Identity PATCH to complete before enabling Guest management on VM.

0.1.9
++++++
* Update API Version from 2020-10-01-preview to 2022-01-10-preview.
* Support for VM delete in retain mode.

0.1.8
++++++
* Displaying asterisks (*****) for password input.

0.1.7
++++++
* Proxy support in vm guest agent.
* Deprecate support to create resource from moref id.
* [BREAKING CHANGE] Fixed guest-agent enable issue. 

0.1.6
++++++
* Fix vm update issue.
* Fix inventory item show.
* Add support for tagging.

0.1.5
++++++
* Fixed inventory item id issue.

0.1.4
++++++
* Add vm extension support.

0.1.3
++++++
* Fixed inventory item issue.

0.1.2
++++++
* Added support for cluster, datastore and host.
* Added support for placement profile.

0.1.1
++++++
* vcenter connection details can be skipped in CLI args, the user will be prompted for the skipped values in that case.

0.1.0
++++++
* Initial release.

