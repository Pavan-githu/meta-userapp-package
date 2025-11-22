# meta-userapp-package

A Yocto Project layer providing user application packages for embedded Linux systems.

## Description

This layer contains user application recipes including:
- LED control applications with various blinking patterns
- HTTPS server for firmware upload and device management
- IoT Security Gateway implementation
- Sample applications and examples for embedded development

## Dependencies

This layer depends on:
- URI: git://git.yoctoproject.org/poky
  - branch: kirkstone
- URI: git://git.openembedded.org/meta-openembedded
  - branch: kirkstone  
- URI: git://git.yoctoproject.org/meta-raspberrypi
  - branch: kirkstone

## Usage

### Adding the Layer

1. Clone this repository:
   ```bash
   git clone https://github.com/pavan-gidaveer_henrg/meta-userapp-package.git
   ```

2. Add the layer to your build:
   ```bash
   bitbake-layers add-layer meta-userapp-package
   ```

### Building Applications

To build the applications provided by this layer:

- Basic LED blink application:
  ```bash
  bitbake blink
  ```

- IoT Security Gateway (when available):
  ```bash
  bitbake iot-security-gateway
  ```

- User application with HTTPS server (when available):
  ```bash
  bitbake user-application
  ```

## Layer Contents

### recipes-apps/
- **blink/**: Simple LED control application with configurable patterns
- **user-application/**: Advanced application with LED control and HTTPS firmware upload server

### recipes-example/
- **example/**: Sample recipe template for creating new applications

## Configuration

The layer provides various configurable options through BitBake variables and application configuration files. See individual recipe documentation for specific configuration options.

## Target Hardware

This layer is primarily designed for:
- Raspberry Pi 3 Model B
- Other ARM-based embedded systems with GPIO support

## Contributing

Please submit patches and issues to the project repository:
https://github.com/pavan-gidaveer_henrg/meta-userapp-package.git

## Maintainer

**Pavan Kumar**  
Email: pavan.gidaveer@henrg.com

## License

This layer is licensed under the MIT License. See COPYING.MIT for details.

## Compatibility

- **Layer Series**: kirkstone
- **Yocto Project**: 4.0.x
- **Poky**: kirkstone branch