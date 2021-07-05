package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class MetaDataNodeTests extends GhidraCodeToCpgSuite {

  override val code: String =
    """
      | int main() {}
      |""".stripMargin

  "should contain exactly one node with all mandatory fields set" in {
    cpg.metaData.l match {
      case List(x) =>
        x.language shouldBe "Ghidra"
        x.version shouldBe "0.1"
        x.overlays shouldBe List("semanticcpg")
      case _ => fail()
    }
  }
}
