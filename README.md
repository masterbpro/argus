[![Open Source](https://img.shields.io/badge/Open-Source-brightgreen)](https://opensource.org/)
[![Apache-2.0 License](https://img.shields.io/github/license/masterbpro/argus)](https://opensource.org/licenses/)
[![Active](http://img.shields.io/badge/Status-Active-green.svg)](https://github.com/masterbpro/argus)

# Argus

**Argus** is a security framework and toolset designed to protect the Linux network stack in diverse environments.

With Argus, you can safeguard your systems by leveraging the power of eBPF for real-time traffic monitoring, advanced
threat detection, and automated network policy enforcement. Argus integrates seamlessly with Linux networking tools and
frameworks, enabling intelligent response mechanisms to block attacks and secure communication between services.

You can use Argus to enhance the security of your cloud-native applications, on-premise systems, or hybrid environments,
creating robust, secure development and production infrastructures.

### Who is Argus?

Argus Panoptes from Greek mythology is a giant with a hundred eyes, several of which were always open, even when he
slept. This made him the perfect guardian.

> ⚠️ **Warning:** This project is in an active development stage. Please avoid installing or using it unless you are
> confident in what you're doing.

## Use-Cases

* Secure your bare-metal Kubernetes cluster
* Monitor and mitigate DDoS attacks
* Detect and respond to anomalous network behavior
* Simplify compliance for regulated environments
* Detect network anomaly

## Versioning

Versioning adheres to the [Semantic Versioning](http://semver.org/) principles.  
A full list of the available releases is available in the GitHub
repository's [Release](https://github.com/masterbpro/argus/releases) section.

## Contributions

Contributions are highly appreciated and very welcomed!

To get started with contributing, check out the [DEVELOPMENT](docs/DEVELOPMENT.md) guide.
It contains all the essential information for setting up your development environment, coding standards, and how to
submit your work.

In case of bugs, please, check if the issue has been already opened by checking
the [GitHub Issues](https://github.com/masterbpro/argus/issues) section.
In case it isn't, you can open a new one: a detailed report will help us to replicate it, assess it, and work on a fix.

You can express your intention in working on the fix on your own.
Commits are used to generate the changelog, and their author will be referenced in it.

In case of **Feature Requests** please use
the [Discussion's Feature Request section](https://github.com/masterbpro/argus/discussions/categories/feature-requests).

## Roadmap

- [x] Minimal bpf program with XDP
- [ ] Develop first ebf program for DoS protection via XDP
- [ ] Analysis and elaboration network attack methods
- [ ] Load test with metrics
- [ ] Packaging and distribution way
    - [ ] binary
    - [ ] deb
    - [ ] helm
- [ ] Documentation

## License

Argus is licensed under Apache 2.0.  
The code is provided as-is with no warranties.
