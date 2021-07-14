import React from 'react';
import { Pivot, PivotItem } from '@fluentui/react'
import { Separator } from '@fluentui/react/lib/Separator';

import SrcDestCombination from "../views/srcDestCombination"
export const Nav = () => (
    <div>
        <Pivot linkSize="large">
            {/* <PivotItem headerText="List Resources">
                <Separator></Separator>
            </PivotItem> */}
            <PivotItem headerText="Src-Dest Combinations">
                <Separator></Separator>
                <SrcDestCombination></SrcDestCombination>
            </PivotItem>
            {/* <PivotItem headerText="Traffic stats">
                <Separator></Separator>
            </PivotItem> */}
        </Pivot>
    </div>
);