# R2PS Base

This is a JAVA implementation of the Remote PAKE Protected Services (R2PS) protocol.

The library is divided into 3 modules:

- Common code shared between both clients and servers
- Client side implementation
- Server side implementation

## Maven

This code is included in projects by the following maven dependencies

### Commons

```
    <dependency>
      <groupId>se.digg.wallet</groupId>
      <artifactId>r2ps-commons</artifactId>
      <version>${project.version}</version>
    </dependency>
```

### Client

```
    <dependency>
      <groupId>se.digg.wallet</groupId>
      <artifactId>r2ps-client</artifactId>
      <version>${project.version}</version>
    </dependency>
```

### Server

```
    <dependency>
      <groupId>se.digg.wallet</groupId>
      <artifactId>r2ps-server</artifactId>
      <version>${project.version}</version>
    </dependency>
```

