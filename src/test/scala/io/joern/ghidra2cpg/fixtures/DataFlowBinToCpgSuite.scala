package io.joern.ghidra2cpg.fixtures

import io.shiftleft.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.utils.ProjectRoot

class DataFlowBinToCpgSuite {

  var semanticsFilename = ProjectRoot.relativise("dataflowengineoss/src/test/resources/default.semantics")
  var semantics: Semantics = _
  implicit var context: EngineContext = _

}
