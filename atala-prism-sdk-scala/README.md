# Compile jars
Go into the folder prism-kotlin-sdk inside the root of atala repository and execute ./gradlew jar. It's recommend to add --max-workers 1 to avoid the creation of too many threads in the compilation time. New folders called credentials, crypto, docs, extras, generator, identity, protos and protoLib will be generated, and inside ./build/libs in each of this folders will be a jar. Also a folder called gradle will be generate, and in this case the jar will be in gradle/wrapper folder.

# Dependencies
You need to add the resolver "https://plugins.gradle.org/m2/" and declare the following dependencies:
"com.benasher44" % "uuid-jvm" % "0.2.3"
"com.benasher44" % "uuid" % "0.2.3"
"io.grpc" % "grpc-kotlin-stub" % "1.0.0"
"io.grpc" % "grpc-netty-shaded" % "1.37.0"
"com.ionspin.kotlin" % "bignum-jvm" % "0.2.3"
"pro.streem.pbandk" % "pbandk-runtime-jvm" % "0.10.0-beta.3"
"org.bouncycastle" % "bcprov-jdk15on" % "1.68"

# Make project in sbt
Generate a sbt project and add a module called KotlinModule (this name can change, but remember change it in the build.sbt). Change in the module iml line 'sourceFolder url="file://$MODULE_DIR$/src"' for 'sourceFolder url="file://$MODULE_DIR$/src/main/kotlin"'. Later, create a folder "main" inside "src" and a folder "kotlin" inside "main".
In our case we create the project and add the module with intelliJ

Later, create a folder lib and copy all the jars obtains for prism-kotlin-sdk

Copy this line to build.sbt

lazy val kotlin = project.in(file("KotlinModule")).settings(
  resolvers += "r1" at "https://plugins.gradle.org/m2/"
).settings(
  libraryDependencies += "com.benasher44" % "uuid-jvm" % "0.2.3"
).settings(
  libraryDependencies += "com.benasher44" % "uuid" % "0.2.3"
).settings(
  libraryDependencies += "io.grpc" % "grpc-kotlin-stub" % "1.0.0"
).settings(
  libraryDependencies += "io.grpc" % "grpc-netty-shaded" % "1.37.0"
).settings(
  libraryDependencies += "com.ionspin.kotlin" % "bignum-jvm" % "0.2.3"
).settings(
  libraryDependencies += "pro.streem.pbandk" % "pbandk-runtime-jvm" % "0.10.0-beta.3"
).settings(
  libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.68"
).settings(
  Compile / unmanagedJars += file("lib/credentials-jvm-0.1.0-bf19ea04.jar")
).settings(
  Compile / unmanagedJars += file("lib/crypto-jvm-0.1.0-bf19ea04.jar")
).settings(
  Compile / unmanagedJars += file("lib/docs-0.1.0-bf19ea04.jar")
).settings(
  Compile / unmanagedJars += file("lib/extras-jvm-0.1.0-bf19ea04.jar")
).settings(
  Compile / unmanagedJars += file("lib/generator-0.1.0-bf19ea04.jar")
).settings(
  Compile / unmanagedJars += file("lib/gradle-wrapper.jar")
).settings(
  Compile / unmanagedJars += file("lib/identity-jvm-0.1.0-bf19ea04.jar")
).settings(
  Compile / unmanagedJars += file("lib/prism-crypto.jar")
).settings(
  Compile / unmanagedJars += file("lib/protos-jvm-0.1.0-bf19ea04.jar")
).settings(
  Compile / unmanagedJars += file("lib/protosLib-0.1.0-bf19ea04.jar")
)

And this line to pludgin.sbt (create it if it's not present)
addSbtPlugin("com.hanhuy.sbt" % "kotlin-plugin" % "2.0.0")


With this you will be able to create the kotlin code files inside the "kotlin" folder.

For run a main in Kotlin, execute sbt in the root of project and run the command "kotlin/run" and the parameters if the main have parameters.

## Use kotlin classes in scala
In the project, create another module called ScalaModule and do the same changes that for the kotlin module, but replace "kotlin" name with "scala".

Later in build.sbt project add this line in the end:
lazy val scala = project.in(file("ScalaModule")).dependsOn(kotlin % "compile->compile;test->test")

With this you can create scala classes in the ScalaModule, in src/main/scala folder, and use the Kotlin functions. For execute a main in scala, run sbt in root project and run the command "scala/run" and the parameters if the main have parameters.

For some reason, intelliJ IDE works fine, except the tool for execute the code into the intelliJ, but it's works in sbt.
