import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './components/App';
import MuiThemeProvider from 'material-ui/styles/MuiThemeProvider';
import {createStore} from "redux";
import {Provider} from "react-redux"
import {rootReducer} from "./components/store/reducers";


const store = createStore(rootReducer);

const test = () => {
    console.log(store.getState());
};

ReactDOM.render(
    <MuiThemeProvider>
        <Provider store={store}>
            <App/>
        </Provider>
        <button onClick={test}>Button for checking store</button>
    </MuiThemeProvider>,
    document.getElementById('root')
);

