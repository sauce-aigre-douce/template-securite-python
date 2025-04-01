def hello_world() -> str:
    """
    Hello world function
    """
    return "Hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice
    """
    interface = ""
    return interface


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""

    def capture_trafic(self) -> None:
        """
        Capture network trafic from an interface
        """
        interface = self.interface

    def sort_network_protocols(self) -> None:
        """
        Sort and return all captured network protocols
        """

    def get_all_protocols(self) -> None:
        """
        Return all protocols captured with total packets number
        """

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary


class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """

        if param == "graph":
            # TODO: generate graph
            graph = ""
            self.graph = graph
        elif param == "array":
            # TODO: generate array
            array = ""
            self.array = array
