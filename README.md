# OpenNebula Windows Contextualization

## Description

This addon produces a Windows Contextualization script to use in Windows Guest VMs running in an OpenNebula Cloud.

The documentation on Windows Contextualization can be found in
the [OpenNebula User's Guide](http://docs.opennebula.org/5.2/operation/vm_setup/context_overview.html).

## MSI package

Requirements for building:

* latest [msitools](https://wiki.gnome.org/msitools)
* binary [rhsrvany.exe](https://github.com/rwmjones/rhsrvany)

Script `generate.sh` builds the MSI package. It's a wrapper around
the `wixl` command from `msitools`. It reads the `package.wxs`, a package
definition in the WiX-like XML format. Package name or version can be
overridden by env. variables `NAME` and `VERSION`. For example:

```bash
$ ./generate.sh
$ NAME=one-context ./generate.sh
$ VERSION=1.0.0 ./generate.sh
```

New package is created as `${NAME}-${VERSION}.msi`,
e.g. `one-context-1.0.0.msi`.

Please ignore following assertion on package build, which is caused
by skipping the attribute `Start` in tag `ServiceControl`. The parameter
is optional in WiX specification, but the `msitools` still counts with it.
Despite that, the package is built.

```
(wixl:22764): wixl-CRITICAL **: wixl_wix_builder_install_mode_to_event: assertion 'modeString != NULL' failed
```

### rhsrvany.exe

On RHEL (CentOS) or Fedora systems the required binary
[rhsrvany.exe](https://github.com/rwmjones/rhsrvany) is distributed as part
of the package `virt-v2v` and placed into `/usr/share/virt-tools/rhsrvany.exe`.
Please copy the EXE into your local repository clone before creating the MSI.

## Authors

* Leader: Jaime Melis jmelis@opennebula.org
* André Monteiro (Universidade de Aveiro)

## Acknowledgements

This addon is largely based upon the work by André Monteiro and Tiago Batista in the [DETI/IEETA Universidade de Aveiro](http://www.ua.pt/). The original guide is available here: [OpenNebula - IEETA](http://wiki.ieeta.pt/wiki/index.php/OpenNebula)
