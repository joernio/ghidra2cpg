name := "ghidra2cpg"
organization := "io.joern"
version := "0.1"
ThisBuild / scalaVersion := "2.13.5"
// don't upgrade to 2.13.6 until https://github.com/com-lihaoyi/Ammonite/issues/1182 is resolved
val cpgVersion = "1.3.211"

ThisBuild / resolvers ++= Seq(
  Resolver.mavenLocal,
  Resolver.mavenCentral,
  Resolver.jcenterRepo,
  "jitpack" at "https://jitpack.io",
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public"
)

ThisBuild / scalacOptions ++= Seq(
  "-deprecation" // Emit warning and location for usages of deprecated APIs.
)

val protoVersion     = "0.8.525"
val scalatestVersion = "3.1.1"

fork := true
javaOptions := Seq("-Djava.protocol.handler.pkgs=ghidra.framework.protocol")

resolvers += Resolver.mavenLocal
trapExit := false

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

enablePlugins(JavaAppPackaging)

Global / onChangedBuildSource := ReloadOnSourceChanges
