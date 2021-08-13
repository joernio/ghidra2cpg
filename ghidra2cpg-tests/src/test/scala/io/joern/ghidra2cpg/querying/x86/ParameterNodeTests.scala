package io.joern.ghidra2cpg.querying.x86

import io.joern.ghidra2cpg.fixtures.GhidraBinToCpgSuite
import io.shiftleft.semanticcpg.language._

class ParameterNodeTests extends GhidraBinToCpgSuite {

  override def beforeAll(): Unit = {
    super.beforeAll()
    buildCpgForBin("x86_64.bin")
  }

  "should contain atLeast one nodes with all mandatory fields set" in {
    cpg.method.name("printf").parameter.name.l.sorted.distinct match {
      case List(x) =>
        x shouldBe "__format"
      case _ => fail()
    }
  }
}
