name := "atala-prism-tests"

version := "0.1"

scalaVersion := "2.13.4"

lazy val kotlin = project.in(file("KotlinModule")).settings(
  resolvers += "r1" at "https://plugins.gradle.org/m2/"
).settings(
  libraryDependencies += "com.benasher44"%"uuid-jvm" % "0.2.3"
).settings(
  libraryDependencies += "com.benasher44"%"uuid" % "0.2.3"
).settings(
  libraryDependencies += "io.grpc" % "grpc-kotlin-stub" % "1.0.0"
).settings(
  libraryDependencies += "io.grpc" % "grpc-netty-shaded" % "1.37.0"
).settings(
  libraryDependencies += "com.ionspin.kotlin"%"bignum-jvm"%"0.2.3"
).settings(
  libraryDependencies += "pro.streem.pbandk"%"pbandk-runtime-jvm"%"0.10.0-beta.3"
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

lazy val scala = project.in(file("ScalaModule")).dependsOn(kotlin % "compile->compile;test->test")

