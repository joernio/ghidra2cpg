name := "ghidra2cpg"
organization := "io.joern"
scalaVersion := "2.13.5"
// don't upgrade to 2.13.6 until https://github.com/com-lihaoyi/Ammonite/issues/1182 is resolved

val cpgVersion = "1.3.223"
val scalatestVersion = "3.1.1"

libraryDependencies ++= Seq(
  "com.github.scopt" %% "scopt"                    % "3.7.1",
  "commons-io"        % "commons-io"               % "2.7",
  "io.shiftleft"      % "ghidra"                   % "10.0_PUBLIC_20210621",
  "io.shiftleft"     %% "codepropertygraph"        % cpgVersion,
  "io.shiftleft"     %% "codepropertygraph-protos" % cpgVersion,
  "io.shiftleft"     %% "dataflowengineoss"        % cpgVersion,
  "io.shiftleft"     %% "semanticcpg"              % cpgVersion,
  "io.shiftleft"     %% "semanticcpg-tests"        % cpgVersion       % Test classifier "tests",
  "org.scalatest"    %% "scalatest"                % scalatestVersion % Test
)

resolvers ++= Seq(
  Resolver.mavenLocal,
  Resolver.mavenCentral,
  Resolver.jcenterRepo,
  "jitpack" at "https://jitpack.io",
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public"
)

scalacOptions ++= Seq(
  "-deprecation" // Emit warning and location for usages of deprecated APIs.
)

fork := true
javaOptions := Seq("-Djava.protocol.handler.pkgs=ghidra.framework.protocol")

resolvers += Resolver.mavenLocal
trapExit := false

enablePlugins(JavaAppPackaging)
enablePlugins(GitVersioning)


scmInfo := Some(ScmInfo(
    url("https://github.com/joernio/ghidra2cpg"),
        "scm:git@github.com:joernio/ghidra2cpg.git"))
homepage := Some(url("https://github.com/joernio/ghidra2cpg/"))
licenses := List("Apache-2.0" -> url("http://www.apache.org/licenses/LICENSE-2.0"))
developers := List(
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
publishTo := sonatypePublishToBundle.value

Global / onChangedBuildSource := ReloadOnSourceChanges
