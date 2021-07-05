package x86.io.joern.ghidra2cpg.querying

import better.files._
import io.joern.ghidra2cpg.Ghidra2Cpg
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.cpgloading.{CpgLoader, CpgLoaderConfig}
import io.shiftleft.semanticcpg.testfixtures.{CodeToCpgFixture, LanguageFrontend}

import java.nio.file.Files
import scala.sys.process._

class GhidraFrontend extends LanguageFrontend {
  override val fileSuffix: String = ".c"

  override def execute(sourceCodeFile: java.io.File): Cpg = {
    val dir = File.newTemporaryDirectory("ghidra2cpg-tests")
    dir.deleteOnExit()

    val f         = sourceCodeFile.listFiles.head
    val absPath   = f.getAbsolutePath
    val tmpBinary = (dir / "binary").toJava.getAbsolutePath
    val cpgBin    = (dir / "cpg.bin").toJava.getAbsolutePath

    val cmd = s"gcc $absPath -o $tmpBinary"
    cmd.!

    // TODO: add ARM binary tests (on arch linux)
    //val armcmd = s"aarch64-linux-gnu-gcc $absPath -o $tmpBinary"
    //armcmd.!

    // TODO: add MIPS binary tests (on arch linux, aur package)
    //val armcmd = s"cross-mipsel-linux-gnu-gcc $absPath -o $tmpBinary"
    //armcmd.!

    val tempDir = Files.createTempDirectory("ghidra2cpg").toFile
    tempDir.deleteOnExit()

    new Ghidra2Cpg(
      tmpBinary,
      Some(cpgBin)
    ).createCpg()

    val odbConfig = overflowdb.Config.withDefaults().withStorageLocation(cpgBin)
    val config    = CpgLoaderConfig.withDefaults.withOverflowConfig(odbConfig)
    CpgLoader.loadFromOverflowDb(config)
  }

}

class GhidraCodeToCpgSuite extends CodeToCpgFixture(new GhidraFrontend) {}
