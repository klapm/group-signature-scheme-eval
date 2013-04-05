README
================================================================================
Partial ISO20008-2.2 implementation to evaluate the scheme applicability on
mobile devices

Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
Johannes Winter
Daniel Hein
Christian Hanser
Peter Teufl
Liqun Chen

Contains Mechanisms 1, 4 and 5 as well as basic infrastructure support, such
as a tiny ECC library supporting Optimal Ate Pairing and general infrastructure
to embed other mechanisms.

================================================================================
TOC
================================================================================

* License
* Building
* Running/Testing
* Adding a new mechanism

================================================================================
LICENSE
================================================================================

This software is available under the "modified" (3-clause) BSD License
[http://opensource.org/licenses/BSD-3-Clause].

================================================================================
BUILDING
================================================================================

The source can be built as any conventional Java program. No special arguments
or libraries needed as it is running standalone. 

There is an ant buildscript at ISO20008/build.xml. The source can be built
using ant with "ant compile". Compiled classes will be put to "classes".
"ant clean" removes this folder and "ant javadoc" will create the JavaDoc
documentation in "doc".

================================================================================
RUNNING/TESTING
================================================================================

Since the implementation is somewhat decoupled from the API (even though both
resides in the same project structure), the underlying implementation can be
entirely changed. To do so, create you own implementation with a central factory
following org.iso200082.common.ISO20008Factory and provide the JVM
argument -Dsig-scheme-impl=<my.factory>. Otherwise, one needs to specify
-Dsig-scheme-impl=org.iso200082.common.ISO20008Factory to make it run.

In the ISO20008Tests (test project) directory is a separate build.xml for
testing purposes. The following targets are known:
- compile   Compiles the test code
- alltests  Runs the entire suite, see AllTests.java, time to get some coffee
- libtests  Library-level tests, revocation testing, see TestLib.java
- ecctests  Framework backend ecc tests, see common/TestECC.java
- hashtests Framework backend hashing tests, see common/TestHash.java
- utiltests Utility function tests, see common/TestUtil.java
- m1tests   Mechanism 1 tests, see m1/TestMechanism1.java
- m4tests   Mechanism 4 tests, see m4/TestMechanism4.java
- m5tests   Mechanism 5 tests, see m5/TestMechanism5.java
- clean     Cleans/removes the classes folder

That ISO20008Tests/build.xml will, on first launch, build the actual project
as well as the test cases. Additionally, junit 4.10 is downloaded and placed
into the lib/ folder if it isn't present.

Note that the tests are preconfigured to some maybe undesirable setting. To
avoid using a prefixed group setup, set SKIP_CREATION in the corresponding test-
cases of the mechanisms 1 and 5 to false. Also, set the identifier in the sub-
classed testcase to the identifier to your desired variant. See the javadoc of 
ISO20008Factory.java for details on the available settings.

================================================================================
ADDING A NEW MECHANISM
================================================================================

Well, the recommended way would be to copy the structure of an existing
mechanism. There is a central file called MxScheme.java in the mechanism's root
package, tying the parties and components of the scheme together and providing
means to parameterize it. Then, there is common/ISO20008Factory, which
registers all the supporting schemes with their supported revocation mechanisms
(see ISO20008Factory.ISO20008Factory()).

All parties are derived from the corresponding Interface classes (Issuer,
Signer, Verifier, Linker, Opener) and have to implement the given methods.
Furthermore, the join process is done at implementation level only, there is
just Issuer#addMember() available from the outside. 

Revocation is basically defined by the abstract AbstractRevocationPolicy class,
which should be derived from when implementing such a revocation policy. A
verifier can then be parameterized with this policy to act differently,
depending on which policy he got. Note that this approach is not always a water-
proof way as revocation processes such as credential update take place at the
issuer's, so there might be need for some creativity.

The structure is actually pretty much defined by the API and abstract classes
there. Nevertheless, quite some room for scheme adaptions is kept as
it turned out that there are no two schemes which are equal in terms of their
parameters, revocation support or linking/opening capability and so on..

================================================================================
ADDING A CUSTOM PRIMITIVE IMPLEMENTATION
================================================================================

If you want to add a custom, maybe native, primitive implementation, you need
to subclass org.iso200082.common.ecc.fields.towerextension.Fq as well as
FqElement and FqDoubleElement. It is probably easyiest to copy one of the 
existing implementations and start from there.
