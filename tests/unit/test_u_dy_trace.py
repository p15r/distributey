"""Tests module dy_trace."""

import inspect

import dy_trace


def dummy_function(
        dummy_argument,
        priv_dummy_argument,
        dummy_argument_nested_dict
):
    """Tests dy_trace.trace_enter()."""
    dy_trace.trace_enter(inspect.currentframe())


class TestDyTrace():
    """Tests module dy_trace."""

    dummy_argument = 'test'
    priv_dummy_argument = 'should_be_camouflaged'
    dummy_argument_nested_dict = {
        'a1': {
            'a11': 'test',
            'priv_a12': 'should_be_camouflaged'
        },
        'b1': {
            'b11': {
                'b111': {
                    'priv_b1111': 'should_be_camouflaged'
                }
            }
        },
        'c1': {
            'c11': 'test'
        }
    }

    def test_trace_enter(self, capfd):
        """Tests if function/method arguments are logged."""

        dummy_function(
            self.dummy_argument,
            self.priv_dummy_argument,
            self.dummy_argument_nested_dict
        )

        captured = capfd.readouterr()

        assert 'Entering "dummy_function"' in captured.err
        assert 'args: {\'dummy_argument\': \'test\'' in captured.err
        assert '\'priv_dummy_argument\': \'******\',' in captured.err
        assert ('\'dummy_argument_nested_dict\': {\'a1\': {\'a11\': \'test\', '
                '\'priv_a12\': \'******\'}, \'b1\': {\'b11\': {\'b111\': '
                '{\'priv_b1111\': \'******\'}}}, \'c1\': '
                '{\'c11\': \'test\'}}}\n') in captured.err

    def test_trace_exit(self, capfd):
        """Tests if return values are logged."""

        ret = 'test123'
        dy_trace.trace_exit(inspect.currentframe(), ret)

        captured = capfd.readouterr()

        assert 'Exiting "test_trace_exit" ret: test123' in captured.err

    def test_trace_enter_nested_dict_depth_exceeded(self, capfd):
        """
        Tests what happens if function argument nested dict depth
        is exceeded.
        """

        dy_trace.NESTED_DICT_DEPTH_MAX = 2

        dummy_function(
            self.dummy_argument,
            self.priv_dummy_argument,
            self.dummy_argument_nested_dict
        )

        captured = capfd.readouterr()

        assert 'Aborting, nested dict depth ("2") exceeded' in captured.err
        assert '{\'priv_b1111\': \'should_be_camouflaged\'}' in captured.err
