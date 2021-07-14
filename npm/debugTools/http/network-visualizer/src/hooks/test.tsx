import { useState } from "react"
import { DetailsListDocumentsExample, Pod } from "../components/podList"
import axios from 'axios';



export default (): [(id: string) => void, Pod[], string] => {
    const [pods, setPods] = useState<Pod[]>([]);
    const [errorMsg, setErrorMsg] = useState("");

    const getPods = async (id: string) => {
        try {
            axios
                .get<Pod[]>("http://localhost:10091/podList/")
                .then(response => {
                    setPods(response.data)
                })
            setErrorMsg("");
        } catch (error) {
            setErrorMsg(error);
        }
    };

    return [getPods, pods, errorMsg];
};