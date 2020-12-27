import click
import questionary as questionary

from myjwt.vulnerabilities import print_decoded


def user_interface(jwt: str):
    click.echo("")
    click.echo("Your jwt is: \n" + jwt)
    click.echo("")
    click.echo("Your jwt decoded is:")
    click.echo("")
    print_decoded(jwt)
    click.echo("")
    test = questionary.select(
        "What do you want to do?",
        choices=["Order a pizza", "Make a reservation", "Ask for opening hours"],
    ).ask()
    click.echo(test)