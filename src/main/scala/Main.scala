import config.*
import plugins.dependencies.DependenciesPlugin
import plugins.weaknesses.WeaknessesPlugin

object Main {

  val appName: String = "InfraMapper"

  protected def run(config: StartupConfiguration): Unit = {
    val engine = config.command match {
      case AnalyseWeaknessesCommand =>
        if (! config.extraCommandOptions.isInstanceOf[AnalyseWeaknessesOptions]) {
          System.err.println(s"Incompatible options ${config.extraCommandOptions} for command ${config.command}")
          System.exit(1)
        }
        new WeaknessesPlugin(config.input, config.extraCommandOptions.asInstanceOf[AnalyseWeaknessesOptions])
      case FetchDependenciesCommand =>
        if (! config.extraCommandOptions.isInstanceOf[FetchDependenciesOptions]) {
          System.err.println(s"Incompatible options ${config.extraCommandOptions} for command ${config.command}")
          System.exit(1)
        }
        new DependenciesPlugin(config.input, config.extraCommandOptions.asInstanceOf[FetchDependenciesOptions])
    }
    engine.run()
  }

  def main(args: Array[String]): Unit = {
    val parser = new ArgsParser(appName)
    val optConfig = parser.parseArgs(args)
    optConfig match {
      case None =>
        System.exit(1)
      case Some(config) => run(config)
    }
  }
}

