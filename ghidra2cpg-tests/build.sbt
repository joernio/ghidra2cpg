name := "ghidra2cpg-tests"

dependsOn(Projects.ghidra2cpg)

val scalatestVersion = "3.1.1"
val cpgVersion = Versions.cpgVersion

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest"         % scalatestVersion % Test,
  "io.shiftleft"  %% "semanticcpg-tests" % cpgVersion       % Test classifier "tests",
)

fork := true
javaOptions := Seq("-Djava.protocol.handler.pkgs=ghidra.framework.protocol")

Test / packageBin / publishArtifact := true
