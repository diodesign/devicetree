## devicetree

This is a simple crate for reading and writing device tree blobs (DTBs). This blob data is typically passed to a kernel or some other low-level code by a bootloader or firmware when a system is powered up. The device tree describes the underlying hardware, such as the location of physical memory and control registers for interfaces and timers, and so on.

This crate is used by [Diosix](https://diosix.org) to boot a system, and to describe virtual hardware environments to guest operating systems. As such, it does not require the standard library. If you wish to use this for your own project, let me know and I'll tidy up the documentation and API.

### Contact and code of conduct <a name="contact"></a>

Please [email](mailto:diodesign@tuta.io) project lead Chris Williams if you have any questions or issues to raise, wish to get involved, have source to contribute, or have found a security flaw. You can, of course, submit pull requests or raise issues via GitHub, though please consider disclosing security-related matters privately. Please also observe the Diosix project's [code of conduct](https://diosix.org/docs/conduct.html) if you wish to participate.

### Copyright and license <a name="copyright"></a>

Copyright &copy; Chris Williams, 2019. See [LICENSE](LICENSE) for distribution and use of source code and binaries.
