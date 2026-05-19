from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
import pyfiglet

console = Console()

def afficher_accueil():
    console.clear()
    
    # 1. Génération du gros titre PQC CHAT
    titre_ascii = pyfiglet.figlet_format("PQC  CHAT", font="slant")
    
    # 2. Création du panneau principal avec des bordures
    contenu_panneau = f"[bold cyan]{titre_ascii}[/bold cyan]\n"
    contenu_panneau += "[dim]Version 0.0.1 · Post-Quantum Secure Protocol[/dim]\n\n"
    contenu_panneau += "Bienvenue dans le chat sécurisé. Configurez vos algorithmes ou tapez ? pour de l'aide.\n\n"
    contenu_panneau += "[bold blue]●[/bold blue] Serveur prêt\n"
    contenu_panneau += "[bold blue]●[/bold blue] Connecté en tant que : [bold white]Bob[/bold white]"

    # On encadre tout ça avec une jolie bordure blanche
    console.print(Panel(contenu_panneau, border_style="white", padding=(1, 2)))
    
    print("\n~/MonRepo [main]")

    # 3. Le prompt de saisie stylisé
    choix = Prompt.ask("[bold green]>[/bold green] Entrez l'algo KEM")
    
    return choix

if __name__ == "__main__":
    afficher_accueil()