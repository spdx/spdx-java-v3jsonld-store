# spdx-java-v3jsonld-store

[![javadoc](https://javadoc.io/badge2/org.spdx/spdx-v3jsonld-store/javadoc.svg)](https://javadoc.io/doc/org.spdx/spdx-v3jsonld-store)
 
Stores SPDX documents in SPDX version 3 compatible JSON-LD format.

This library utilizes the [SPDX Java Library Storage Interface](https://github.com/spdx/Spdx-Java-Library#storage-interface) extending the `ExtendedSpdxStore` which allows for utilizing any underlying store which implements the [SPDX Java Library Storage Interface](https://github.com/spdx/Spdx-Java-Library#storage-interface).

## Code quality badges

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=spdx-v3jsonld-store&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=spdx-v3jsonld-store)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=spdx-v3jsonld-store&metric=bugs)](https://sonarcloud.io/summary/new_code?id=spdx-v3jsonld-store)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=spdx-v3jsonld-store&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=spdx-v3jsonld-store)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=spdx-v3jsonld-store&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=spdx-v3jsonld-store)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=spdx-v3jsonld-store&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=spdx-v3jsonld-store)

## Using the Library

This library is intended to be used in conjunction with the [SPDX Java Library](https://github.com/spdx/Spdx-Java-Library).

Create an instance of a store which implements the [SPDX Java Library Storage Interface](https://github.com/spdx/Spdx-Java-Library#storage-interface).  For example, the [InMemSpdxStore](https://github.com/spdx/Spdx-Java-Library/blob/master/src/main/java/org/spdx/storage/simple/InMemSpdxStore.java) is a simple in-memory storage suitable for simple file serializations and deserializations.

Create an instance of `JsonLDStore(IModelStore baseStore, boolean pretty)` passing in the instance of a store created above along with the format.  If true, `pretty` will produce more human-readable output including indents as well as license expressions rather than full model license details.

## Serializing and Deserializing

This library supports the `ISerializableModelStore` interface for serializing and deserializing files.

## API Documentation

- [Released API documentation](https://www.javadoc.io/doc/org.spdx/spdx-v3jsonld-store) (as released on Maven Central)
- [Development API documentation](https://spdx.github.io/spdx-java-v3jsonld-store/) (updated with each GitHub change)

## Development Status

Reasonably stable.
