import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';

import '../components/App/index.css';
import '../components/ui/ReactTable.css';
import '../glaze-ui.css';
import '../glaze-ui-components.css';
import configureStore from '../configureStore';
import reducers from '../reducers/login';
import '../i18n';
import '../productIdentity';

import { Login } from './Login';
import { LoginState } from '../initialState';

const store = configureStore<LoginState>(reducers, {});

ReactDOM.render(
    <Provider store={store}>
        <Login />
    </Provider>,
    document.getElementById('root'),
);
