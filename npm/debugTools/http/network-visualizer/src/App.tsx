import React from 'react';
import { Stack, IStackTokens, IStackStyles } from '@fluentui/react';
import './App.css';
import { Nav } from './components/topnav'


const stackTokens: IStackTokens = { childrenGap: 50, padding: 50 };
const stackStyles: Partial<IStackStyles> = {
  root: {
    margin: '0',
    marginLeft: '5%',
    textAlign: 'start',
    color: '#605e5c',
  },
};

export const App: React.FunctionComponent = () => {
  return (
    <Stack verticalFill styles={stackStyles} tokens={stackTokens}>
      <Nav></Nav>
    </Stack>
  );
};
