from src.tp1.utils.lib import hello_world

def test_when_hello_world_then_return_hello_world():
    # Given
    string = "Hello world"

    # When
    result = hello_world()

    # Then
    assert result == string