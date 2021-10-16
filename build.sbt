name := "ghidra2cpg"
ThisBuild/organization := "io.joern"
ThisBuild/scalaVersion := "2.13.5"
// don't upgrade to 2.13.6 until https://github.com/com-lihaoyi/Ammonite/issues/1182 is resolved

val cpgVersion = "1.3.379"

ThisBuild / resolvers ++= Seq(
  Resolver.mavenLocal,
  Resolver.mavenCentral,
  Resolver.jcenterRepo,
  "jitpack" at "https://jitpack.io",
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public"
)

scalacOptions ++= Seq(
  "-deprecation" // Emit warning and location for usages of deprecated APIs.
)


ThisBuild / resolvers += Resolver.mavenLocal
trapExit := false

sonatypeCredentialHost := "s01.oss.sonatype.org"
ThisBuild/scmInfo := Some(ScmInfo(
    url("https://github.com/joernio/ghidra2cpg"),
        "scm:git@github.com:joernio/ghidra2cpg.git"))
ThisBuild/homepage := Some(url("https://github.com/joernio/ghidra2cpg/"))
ThisBuild/licenses := List("Apache-2.0" -> url("http://www.apache.org/licenses/LICENSE-2.0"))
ThisBuild/developers := List(
  /* sonatype requires this to be non-empty */
  Developer(
    "itsacoderepo",
    "Niko Schmidt",
    "niko@joern.io",
    url("https://github.com/itsacoderepo")
  ),
  Developer(
    "fabsx00",
    "Fabian Yamaguchi",
    "fabs@joern.io",
    url("https://github.com/fabsx00")
  )
)
ThisBuild/publishTo := sonatypePublishToBundle.value

lazy val ghidra2cpg = Projects.ghidra2cpg
lazy val ghidra2cpgtests = Projects.ghidra2cpgtests.dependsOn(ghidra2cpg)

Global / onChangedBuildSource := ReloadOnSourceChanges
