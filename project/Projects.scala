import sbt._

object Projects {
  lazy val ghidra2cpg = project.in(file("ghidra2cpg"))
  lazy val ghidra2cpgtests = project.in(file("ghidra2cpg-tests"))
}
