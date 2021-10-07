name := "ghidra2cpg"

enablePlugins(JavaAppPackaging)

val cpgVersion = Versions.cpgVersion

libraryDependencies ++= Seq(
  "com.github.scopt" %% "scopt"                    % "3.7.1",
  "commons-io"        % "commons-io"               % "2.7",
  "io.shiftleft"      % "ghidra"                   % "10.0_PUBLIC_20210621",
  "io.shiftleft"     %% "codepropertygraph"        % cpgVersion,
  "io.shiftleft"     %% "codepropertygraph-protos" % cpgVersion,
  "io.shiftleft"     %% "dataflowengineoss"        % cpgVersion,
  "io.shiftleft"     %% "semanticcpg"              % cpgVersion,
)
