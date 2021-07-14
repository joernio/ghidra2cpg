package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class ParameterNodeTests extends GhidraCodeToCpgSuite {

  override val code: String = ""

  "should contain atLeast one nodes with all mandatory fields set" in {
    cpg.method.name("printf").parameter.name.l.sorted.distinct match {
      case List(x) =>
        x shouldBe "__format"
      case _ => fail()
    }
  }
}
