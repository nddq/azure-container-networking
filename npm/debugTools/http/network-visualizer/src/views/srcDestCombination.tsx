import * as React from 'react';
import { TextField } from '@fluentui/react/lib/TextField';
import { Stack, IStackStyles } from '@fluentui/react';
import { PrimaryButton } from '@fluentui/react/lib/Button';
import { DetailsListDocumentsExample, Pod } from "../components/podList"
import { SrcDestGraph } from "../components/srcDestGraph"
import { Separator } from '@fluentui/react/lib/Separator';
import testHook from "../hooks/test";



const stackTokens = { childrenGap: 30 };
const topStackStyles: Partial<IStackStyles> = { root: { textAlign: 'start', } };
const midStackStyles: Partial<IStackStyles> = { root: { textAlign: 'start', } };


export default function SrcDestCombination() {
    const [getPods, pods, errorMessage] = testHook();
    return (
        <div>
            <Stack tokens={stackTokens}>
                <Stack horizontal tokens={stackTokens} styles={topStackStyles}>
                    <TextField label="Source selection" />
                    <TextField label="Destination selection" />
                    <Stack verticalAlign="end">
                        <PrimaryButton text="Submit" onClick={() => getPods("123")} />
                    </Stack>
                </Stack>
                <Stack horizontal tokens={stackTokens} styles={midStackStyles}>
                    <SrcDestGraph />
                </Stack>
                <Stack horizontal horizontalAlign="baseline" tokens={stackTokens}>
                    <Stack horizontal horizontalAlign="start">
                        <DetailsListDocumentsExample pods={pods} />
                    </Stack>
                    <Separator vertical />
                    <Stack horizontal horizontalAlign="start">
                        <DetailsListDocumentsExample pods={pods} />
                    </Stack>
                </Stack>

            </Stack>
        </div>
    )
};