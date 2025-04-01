from src.tp1.utils.lib import choose_interface


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
