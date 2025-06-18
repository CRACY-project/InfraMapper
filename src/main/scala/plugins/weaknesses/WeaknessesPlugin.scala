package plugins.weaknesses

import config.AnalyseWeaknessesOptions
import plugins.SCAnsiblePlugin

import scala.sys.process._

class WeaknessesPlugin(file: String, config: AnalyseWeaknessesOptions) extends SCAnsiblePlugin {
  protected def constructCommand(): String = {
    s"""scansible check --enable-security '$file' """
  }
  override def internalRun(): Unit = {
    val command: String = constructCommand()
    val output = command.!!
    println(Console.RED + output + Console.RESET)
  }
}
